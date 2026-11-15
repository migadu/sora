//go:build integration

package imap_test

import (
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// Literal entry names must survive IMAP quoting and select only their own
// descendants, for both server and mailbox metadata and every depth.
func TestIMAP_MetadataLiteralDescendants(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	c, err := imapclient.DialInsecure(srv.Address, nil)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())
	const underscore = `/private/vendor/sora/a_b`
	const backslash = `/private/vendor/sora/c\`
	value := []byte("value")
	entries := map[string]*[]byte{}
	for _, name := range []string{
		underscore, underscore + "/x", underscore + "/x/y",
		backslash, backslash + "/x", backslash + "/x/y",
		`/private/vendor/sora/axb/z`, `/private/vendor/sora/c/z`,
	} {
		entries[name] = &value
	}
	for _, mailbox := range []string{"", "INBOX"} {
		require.NoError(t, c.SetMetadata(mailbox, entries).Wait())
		for _, roots := range [][]string{{underscore}, {backslash}, {underscore, backslash}} {
			for _, depth := range []imap.GetMetadataDepth{imap.GetMetadataDepthZero, imap.GetMetadataDepthOne, imap.GetMetadataDepthInfinity} {
				result, err := c.GetMetadata(mailbox, roots, &imap.GetMetadataOptions{Depth: depth}).Wait()
				require.NoError(t, err)
				var want, got []string
				for _, root := range roots {
					want = append(want, root)
					if depth != imap.GetMetadataDepthZero {
						want = append(want, root+"/x")
					}
					if depth == imap.GetMetadataDepthInfinity {
						want = append(want, root+"/x/y")
					}
				}
				for name := range result.Entries {
					got = append(got, name)
				}
				require.ElementsMatch(t, want, got, "mailbox=%q roots=%q depth=%v", mailbox, roots, depth)
			}
		}
	}
}
