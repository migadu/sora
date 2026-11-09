//go:build integration

package imap_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func sharedMailboxSettings(allowUserCreate, allowAnyone bool) *common.IMAPServerOpts {
	return &common.IMAPServerOpts{SharedMailboxes: &config.SharedMailboxesConfig{
		Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea",
		AllowUserCreate: allowUserCreate, AllowAnyoneIdentifier: allowAnyone,
	}}
}

func mailboxNames(t *testing.T, c *imapclient.Client) []string {
	t.Helper()
	mailboxes, err := c.List("", "*", nil).Collect()
	require.NoError(t, err)
	names := make([]string, 0, len(mailboxes))
	for _, m := range mailboxes {
		names = append(names, m.Mailbox)
	}
	return names
}

// TestSharedMailboxes_AllowUserCreate covers half of issue #159. config.toml.example
// documents `allow_user_create = false  # (false = admin-only)`, and false is the
// default, yet any user could CREATE a shared mailbox. With it false, a user can't
// create a new top-level shared mailbox, by CREATE or by a RENAME that would create
// one; using, renaming and creating children in one an administrator created works.
func TestSharedMailboxes_AllowUserCreate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(false, true))
	defer server.Close()
	member, _ := createSecondUser(t, server, "example.com", "usercreate")

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(owner.Email, owner.Password).Wait())

	ts := common.GetTimestamp()
	refused := []string{fmt.Sprintf("Shared/Team-%d", ts), fmt.Sprintf("Shared/Parent-%d/Child", ts)}
	for _, name := range refused {
		requireResponseCode(t, c.Create(name, nil).Wait(), imap.ResponseCodeNoPerm, "CREATE "+name)
	}
	names := mailboxNames(t, c)
	for _, name := range append(refused, fmt.Sprintf("Shared/Parent-%d", ts)) {
		require.NotContains(t, names, name, "a refused CREATE left it behind")
	}
	for _, name := range names {
		require.False(t, name == "Shared", "a refused CREATE created the namespace root")
	}
	personal := fmt.Sprintf("Projects-%d", ts)
	require.NoError(t, c.Create(personal, nil).Wait())
	defer func() { c.Delete(personal).Wait() }()

	// An administrator creates the shared mailbox, as sora-admin mailbox create does:
	// with the shared mailbox settings, and allowed to create it.
	adminCfg := &config.Config{SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", AllowUserCreate: true}}
	adminCtx := context.WithValue(context.Background(), consts.ConfigContextKey, adminCfg)
	ownerID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	byAdmin := fmt.Sprintf("Shared/ByAdmin-%d", ts)
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, byAdmin))
	renamed := fmt.Sprintf("Shared/Renamed-%d", ts)
	defer func() {
		c.Delete(renamed).Wait()
		c.Delete(byAdmin).Wait()
	}()

	require.NoError(t, c.SetACL(byAdmin, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lr")).Wait(),
		"the administrator's mailbox is shared")
	newParent := fmt.Sprintf("Shared/NewParent-%d", ts)
	requireResponseCode(t, c.Rename(byAdmin, newParent+"/ByAdmin", nil).Wait(), imap.ResponseCodeNoPerm, "RENAME into a new parent")
	require.NotContains(t, mailboxNames(t, c), newParent)
	child := byAdmin + "/Child"
	require.NoError(t, c.Create(child, nil).Wait(), "CREATE inside an existing shared mailbox")
	require.NoError(t, c.Rename(byAdmin, renamed, nil).Wait(), "RENAME within the namespace, creating nothing")
	defer func() { c.Delete(renamed + "/Child").Wait() }()
}

// TestSharedMailboxes_AllowUserCreate_PersonalNamesake: with allow_user_create false a
// user may create mailboxes inside an existing shared mailbox, and those are shared.
// The existing one must therefore BE shared, not merely be found under the shared
// name. The User API and Sieve fileinto :create make personal mailboxes there
// (without the shared settings), and a personal "shared/Team" from before namespace
// matching ignored case answers to "Shared/Team". Either let the user create, and
// then grant, shared mailboxes of their own.
func TestSharedMailboxes_AllowUserCreate_PersonalNamesake(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(false, true))
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(owner.Email, owner.Password).Wait())

	ts := common.GetTimestamp()
	ownerID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(context.Background(), owner.Email)
	require.NoError(t, err)
	// Personal mailboxes under the shared name, as the User API creates them.
	lowercase := fmt.Sprintf("shared/Team-%d", ts)
	planted := fmt.Sprintf("Shared/Planted-%d", ts)
	for _, name := range []string{lowercase, planted} {
		require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(context.Background(), ownerID, name))
	}
	adminCfg := &config.Config{SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", AllowUserCreate: true}}
	byAdmin := fmt.Sprintf("Shared/ByAdmin-%d", ts)
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(
		context.WithValue(context.Background(), consts.ConfigContextKey, adminCfg), ownerID, byAdmin))
	defer func() {
		for _, name := range []string{byAdmin, planted, lowercase} {
			c.Delete(name).Wait()
		}
	}()

	inLowercase := fmt.Sprintf("Shared/Team-%d/Child", ts)
	inPlanted := planted + "/Child"
	for _, name := range []string{inLowercase, inPlanted} {
		requireResponseCode(t, c.Create(name, nil).Wait(), imap.ResponseCodeNoPerm, "CREATE "+name)
	}
	// RENAME of the administrator's shared mailbox would create its new parent.
	newParent := fmt.Sprintf("Shared/Team-%d/New", ts)
	requireResponseCode(t, c.Rename(byAdmin, newParent+"/ByAdmin", nil).Wait(), imap.ResponseCodeNoPerm, "RENAME into "+newParent)

	names := mailboxNames(t, c)
	for _, name := range []string{inLowercase, inPlanted, newParent} {
		require.NotContains(t, names, name, "a refused CREATE or RENAME left it behind")
	}
	require.Contains(t, names, byAdmin)
}

// TestSharedMailboxes_AllowAnyoneIdentifier covers the other half of issue #159:
// allow_anyone_identifier defaults to false, yet SETACL could grant "anyone". With it
// false, nothing can be granted to "anyone" (SETACL answers NO [CANNOT], LISTRIGHTS
// offers nothing), while a grant made before can still be taken away.
func TestSharedMailboxes_AllowAnyoneIdentifier(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(true, false))
	defer server.Close()
	member, _ := createSecondUser(t, server, "example.com", "anyoneflag")

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(owner.Email, owner.Password).Wait())

	shared := fmt.Sprintf("Shared/AnyoneFlag-%d", common.GetTimestamp())
	require.NoError(t, c.Create(shared, nil).Wait())
	defer func() { c.Delete(shared).Wait() }()

	for _, mod := range []imap.RightModification{imap.RightModificationReplace, imap.RightModificationAdd} {
		requireResponseCode(t, c.SetACL(shared, "anyone", mod, imap.RightSet("lr")).Wait(), imap.ResponseCodeCannot, "SETACL anyone")
	}
	data, err := c.ListRights(shared, "anyone").Wait()
	require.NoError(t, err)
	require.Empty(t, data.RequiredRights.String()+rightGroups(data), "LISTRIGHTS anyone")
	require.NoError(t, c.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lr")).Wait())

	// A grant from before the setting was turned off can still be reduced and removed.
	ownerID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(context.Background(), owner.Email)
	require.NoError(t, err)
	require.NoError(t, server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(context.Background(), ownerID, "anyone", shared, "lr"))
	require.NoError(t, c.SetACL(shared, "anyone", imap.RightModificationRemove, imap.RightSet("r")).Wait())
	require.NoError(t, c.DeleteACL(shared, "anyone").Wait())
	acl, err := c.GetACL(shared).Wait()
	require.NoError(t, err)
	_, listed := acl.Rights["anyone"]
	require.False(t, listed)
}

// TestSoraAdminMailboxCreateMakesSharedMailbox: with allow_user_create false, an
// administrator creates shared mailboxes with sora-admin mailbox create, so that must
// create a real shared mailbox. It used to create one without the shared mailbox
// settings: a personal mailbox under the shared prefix, which could not be shared.
func TestSoraAdminMailboxCreateMakesSharedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	base, err := os.ReadFile(common.GetTestConfigPath(t))
	require.NoError(t, err)
	// The server fixture honors SORA_TEST_DB_NAME; the subprocess must use that
	// same database rather than the repository config's default test database.
	var settings map[string]any
	_, err = toml.Decode(string(base), &settings)
	require.NoError(t, err)
	if name := os.Getenv("SORA_TEST_DB_NAME"); name != "" {
		for _, key := range []string{"write", "read"} {
			if endpoint, ok := settings["database"].(map[string]any)[key].(map[string]any); ok {
				endpoint["name"] = name
			}
		}
	}
	settings["shared_mailboxes"] = map[string]any{
		"enabled": true, "namespace_prefix": "Shared/", "allow_user_create": false,
	}
	var encoded bytes.Buffer
	require.NoError(t, toml.NewEncoder(&encoded).Encode(settings))
	configPath := filepath.Join(t.TempDir(), "sora-admin.toml")
	require.NoError(t, os.WriteFile(configPath, encoded.Bytes(), 0o600))

	name := fmt.Sprintf("Shared/AdminMade-%d", common.GetTimestamp())
	out, err := exec.Command(common.GetSoraAdminBinary(t), "--config", configPath,
		"mailbox", "create", "--email", owner.Email, "--mailbox", name).CombinedOutput()
	require.NoError(t, err, "sora-admin mailbox create: %s", out)

	var isShared bool
	var ownerDomain *string
	require.NoError(t, server.ResilientDB.QueryRowWithRetry(context.Background(), `
		SELECT COALESCE(m.is_shared, FALSE), m.owner_domain
		FROM mailboxes m JOIN credentials c ON c.account_id = m.account_id AND c.primary_identity
		WHERE m.name = $1 AND c.address = $2 AND m.deleted_at IS NULL
	`, name, owner.Email).Scan(&isShared, &ownerDomain))
	require.True(t, isShared, "sora-admin created %s as a personal mailbox", name)
	require.NotNil(t, ownerDomain)
}
